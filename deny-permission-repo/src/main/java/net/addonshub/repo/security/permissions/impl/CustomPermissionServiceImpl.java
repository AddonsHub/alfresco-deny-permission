/*
 * #%L
 * Alfresco Repository
 * %%
 * Copyright (C) 2005 - 2016 Alfresco Software Limited
 * %%
 * This file is part of the Alfresco software.
 * If the software was purchased under a paid Alfresco license, the terms of
 * the paid license agreement will prevail.  Otherwise, the software is
 * provided under the following open source license terms:
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */
package net.addonshub.repo.security.permissions.impl;

import org.alfresco.repo.security.permissions.PermissionServiceSPI;
import org.alfresco.repo.security.permissions.impl.PermissionServiceImpl;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.traitextender.Extensible;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Extension of a permissions service to allow Deny permissions
 *
 * @author AddonsHub
 */
public class CustomPermissionServiceImpl extends PermissionServiceImpl implements PermissionServiceSPI,Extensible
{

    private static Log logger = LogFactory.getLog(CustomPermissionServiceImpl.class);

    //The permission group to deny name comes from alfresco-global.properties
    protected String permissionGroupDeny = "";

    /**
     * @param permissionGroupDeny the anyDenyDenies to set
     */
    public void setPermissionGroupDeny(String permissionGroupDeny)
    {
        this.permissionGroupDeny = permissionGroupDeny;
    }



    /**
     * Standard spring construction.
     */
    public CustomPermissionServiceImpl()
    {
        super();

    }

    @Override
    public void setPermission(NodeRef nodeRef, String authority, String perm, boolean allow) {
        //Check if permission group is Denied
        if(perm.equals(this.permissionGroupDeny)){
            allow = false;
        }
        super.setPermission(nodeRef, authority, perm, allow);
    }

}
