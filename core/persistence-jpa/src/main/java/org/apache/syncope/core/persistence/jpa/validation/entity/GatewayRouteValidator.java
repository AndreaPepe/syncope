/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.persistence.jpa.validation.entity;

import javax.validation.ConstraintValidatorContext;
import org.apache.syncope.common.lib.types.EntityViolationType;
import org.apache.syncope.core.persistence.api.entity.GatewayRoute;

public class GatewayRouteValidator extends AbstractValidator<GatewayRouteCheck, GatewayRoute> {

    @Override
    public boolean isValid(final GatewayRoute route, final ConstraintValidatorContext context) {
        context.disableDefaultConstraintViolation();

        boolean isValid = true;

        if (isHtml(route.getName())) {
            context.buildConstraintViolationWithTemplate(
                    getTemplate(EntityViolationType.InvalidName, "Invalid name")).
                    addPropertyNode("name").addConstraintViolation();

            isValid = false;
        }

        if (route.getPredicates().size() > 1) {
            if (route.getPredicates().stream().allMatch(predicate -> predicate.getCond() != null)) {
                context.buildConstraintViolationWithTemplate(
                        getTemplate(EntityViolationType.InvalidValueList,
                                "Cond must be set when predicates are more than one")).
                        addPropertyNode("predicates").addConstraintViolation();
            }

            isValid = false;
        }

        return isValid;
    }
}
