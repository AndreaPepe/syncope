/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.syncope.core.provisioning.camel.producer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.camel.Endpoint;
import org.apache.camel.Exchange;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.common.lib.types.ResourceOperation;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.task.PropagationTask;
import org.apache.syncope.core.provisioning.api.PropagationByResource;
import org.apache.syncope.core.provisioning.api.data.GroupDataBinder;
import org.apache.syncope.core.provisioning.api.propagation.PropagationReporter;
import org.apache.syncope.core.provisioning.camel.AnyType;

public class DeleteProducer extends AbstractProducer {

    private UserDAO userDAO;
    private GroupDataBinder groupDataBinder;

    public DeleteProducer(final Endpoint endpoint, final AnyType anyType, final UserDAO userDao,
                          final GroupDataBinder groupDataBinder) {
        super(endpoint, anyType);
        this.userDAO = userDao;
        this.groupDataBinder = groupDataBinder;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void process(final Exchange exchange) throws Exception {
        String key = exchange.getIn().getBody(String.class);
        Set<String> excludedResources = exchange.getProperty("excludedResources", Set.class);
        Boolean nullPriorityAsync = exchange.getProperty("nullPriorityAsync", Boolean.class);

        if (getAnyType() == AnyType.user) {
            PropagationByResource propByRes = new PropagationByResource();
            propByRes.set(ResourceOperation.DELETE, userDAO.findAllResourceNames(key));

            // Note here that we can only notify about "delete", not any other
            // task defined in workflow process definition: this because this
            // information could only be available after uwfAdapter.delete(), which
            // will also effectively remove user from db, thus making virtually
            // impossible by NotificationManager to fetch required user information
            List<PropagationTask> tasks = getPropagationManager().getDeleteTasks(
                    AnyTypeKind.USER,
                    key,
                    propByRes,
                    excludedResources);

            PropagationReporter propagationReporter = getPropagationTaskExecutor().execute(tasks, nullPriorityAsync);

            exchange.setProperty("statuses", propagationReporter.getStatuses());
        } else if (getAnyType() == AnyType.group) {
            List<PropagationTask> tasks = new ArrayList<>();

            // Generate propagation tasks for deleting users from group resources, if they are on those resources only
            // because of the reason being deleted (see SYNCOPE-357)
            for (Map.Entry<String, PropagationByResource> entry
                    : groupDataBinder.findUsersWithTransitiveResources(key).entrySet()) {

                tasks.addAll(getPropagationManager().getDeleteTasks(
                        AnyTypeKind.USER,
                        entry.getKey(),
                        entry.getValue(),
                        excludedResources));
            }
            for (Map.Entry<String, PropagationByResource> entry
                    : groupDataBinder.findAnyObjectsWithTransitiveResources(key).entrySet()) {

                tasks.addAll(getPropagationManager().getDeleteTasks(
                        AnyTypeKind.ANY_OBJECT,
                        entry.getKey(),
                        entry.getValue(),
                        excludedResources));
            }

            // Generate propagation tasks for deleting this group from resources
            tasks.addAll(getPropagationManager().getDeleteTasks(
                    AnyTypeKind.GROUP,
                    key,
                    null,
                    null));

            PropagationReporter propagationReporter = getPropagationTaskExecutor().execute(tasks, nullPriorityAsync);

            exchange.setProperty("statuses", propagationReporter.getStatuses());
        } else if (getAnyType() == AnyType.any) {
            List<PropagationTask> tasks = getPropagationManager().getDeleteTasks(
                    AnyTypeKind.ANY_OBJECT,
                    key,
                    null,
                    excludedResources);
            PropagationReporter propagationReporter = getPropagationTaskExecutor().execute(tasks, nullPriorityAsync);

            exchange.setProperty("statuses", propagationReporter.getStatuses());
        }
    }

}
