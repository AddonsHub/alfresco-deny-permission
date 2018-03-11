package net.addonshub.denyPermission.jscript;

import org.alfresco.opencmis.CMISConnector;
import org.alfresco.repo.processor.BaseProcessorExtension;
import org.alfresco.service.ServiceRegistry;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.security.AccessPermission;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ImporterTopLevel;
import org.mozilla.javascript.Scriptable;

import java.util.*;

public class CustomPermissionsProcessorExtension extends BaseProcessorExtension {

    private static Log logger = LogFactory.getLog(CustomPermissionsProcessorExtension.class);

    protected ServiceRegistry services = null;

    public void setServiceRegistry(ServiceRegistry serviceRegistry)
    {
        this.services = serviceRegistry;
    }

    /**
     * @see org.alfresco.repo.jscript.Scopeable#setScope(org.mozilla.javascript.Scriptable)
     */
    public Scriptable getScope()
    {
        Context cx = Context.enter();
        return initScope(cx,true,false);

    }

    protected Scriptable initScope(Context cx, boolean secure, boolean sealed)
    {
        Scriptable scope;
        if (secure)
        {
            // Initialise the non-secure scope
            // allow access to all libraries and objects, including the importer
            // @see http://www.mozilla.org/rhino/ScriptingJava.html
            scope = new ImporterTopLevel(cx, sealed);
        }
        else
        {
            // Initialise the secure scope
            scope = cx.initStandardObjects(null, sealed);
            // remove security issue related objects - this ensures the script may not access
            // unsecure java.* libraries or import any other classes for direct access - only
            // the configured root host objects will be available to the script writer
            scope.delete("Packages");
            scope.delete("getClass");
            scope.delete("java");
        }
        return scope;
    }

    /**
     * @return Array of permissions applied to this Node, including inherited.
     *         Strings returned are of the format [ALLOWED|DENIED];[USERNAME|GROUPNAME];PERMISSION for example
     *         ALLOWED;kevinr;Consumer so can be easily tokenized on the ';' character.
     */
    public Scriptable getPermissions(NodeRef nodeRef)
    {
        return Context.getCurrentContext().newArray(getScope(), retrieveAllSetPermissions(nodeRef,false, false));
    }

    /**
     * @return Array of permissions applied directly to this Node (does not include inherited).
     *         Strings returned are of the format [ALLOWED|DENIED];[USERNAME|GROUPNAME];PERMISSION for example
     *         ALLOWED;kevinr;Consumer so can be easily tokenized on the ';' character.
     */
    public Scriptable getDirectPermissions(NodeRef nodeRef)
    {
        return Context.getCurrentContext().newArray(getScope(), retrieveAllSetPermissions(nodeRef,true, false));
    }

    /**
     * @return Sorted list of <code>AccessPermission</code> based on <code>CMISConnector.AccessPermissionComparator</code>
     *         and <code>AccessStatus</code> of the permission for an authority, including Denied permissions
     */
    public static List<AccessPermission> getSortedACLs(Set<AccessPermission> acls)
    {
        ArrayList<AccessPermission> ordered = new ArrayList<AccessPermission>(acls);
        Map<String, AccessPermission> deDuplicatedPermissions = new HashMap<String, AccessPermission>(acls.size());
        Collections.sort(ordered, new CMISConnector.AccessPermissionComparator());
        for (AccessPermission current : ordered)
        {
            String composedKey = current.getAuthority() + current.getPermission();
            if (logger.isDebugEnabled())
                logger.debug("Composed Key: " + current.toString());
            deDuplicatedPermissions.put(composedKey, current);
        }

        return new ArrayList<AccessPermission>(deDuplicatedPermissions.values());
    }

    /**
     * Helper to construct the response object for the various getPermissions() calls.
     *
     * @param direct    True to only retrieve direct permissions, false to get inherited also
     * @param full      True to retrieve full data string with [INHERITED|DIRECT] element
     *                  This exists to maintain backward compatibility with existing permission APIs.
     *
     * @return Object[] of packed permission strings.
     */
    protected Object[] retrieveAllSetPermissions(NodeRef nodeRef, boolean direct, boolean full)
    {
        Set<AccessPermission> acls = this.services.getPermissionService().getAllSetPermissions(nodeRef);
        List<Object> permissions = new ArrayList<Object>(acls.size());
        List<AccessPermission> ordered = getSortedACLs(acls);
        for (AccessPermission permission : ordered)
        {
            if (!direct || permission.isSetDirectly())
            {
                StringBuilder buf = new StringBuilder(64);
                buf.append(permission.getAccessStatus())
                        .append(';')
                        .append(permission.getAuthority())
                        .append(';')
                        .append(permission.getPermission());
                if (full)
                {
                    buf.append(';').append(permission.isSetDirectly() ? "DIRECT" : "INHERITED");
                }
                permissions.add(buf.toString());
            }
        }
        return (Object[])permissions.toArray(new Object[permissions.size()]);
    }

}
