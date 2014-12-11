package id.thrawnca.security;

import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Encapsulates the security context, but makes it available
 * to callers with sufficient privileges.
 * @author Carl Antuar
 */
public final class SecurityContext {

  /** The permission needed to unpack the class context. */
  public static final Permission CLASS_PERMISSION =
    new RuntimePermission("createSecurityManager");

  /** The additional permission needed to unpack the protection domains. */
  public static final Permission DOMAIN_PERMISSION =
    new RuntimePermission("getProtectionDomain");

  /** The call stack. */
  private final Class[] classContext;

  /** The protection domains associated with the call stack. */
  private final Map<Class, ProtectionDomain> protectionDomains;

  /**
   * Construct a SecurityContext for the specified call stack
   * and protection domains.
   * @param classes The call stack.
   * @param domains The protection domains associated with the call stack.
   */
  public SecurityContext(
      final Class[] classes,
      final Map<Class, ProtectionDomain> domains) {
    classContext = (Class[]) classes.clone();
    protectionDomains = Collections.unmodifiableMap(
      new HashMap<Class, ProtectionDomain>(domains)
    );
  }

  /**
   * Requires runtime permission "createSecurityManager".
   * @return The call stack associated with this context.
   */
  public Class[] getClassContext() {
    final SecurityManager manager = System.getSecurityManager();
    if (manager != null) {
      manager.checkPermission(CLASS_PERMISSION);
    }
    return (Class[]) classContext.clone();
  }

  /**
   * Requires runtime permissions "createSecurityManager"
   * and "getProtectionDomain".
   * @return The protection domains relevant to this context.
   */
  public Map<Class, ProtectionDomain> getProtectionDomains() {
    final SecurityManager manager = System.getSecurityManager();
    if (manager != null) {
      manager.checkPermission(CLASS_PERMISSION);
      manager.checkPermission(DOMAIN_PERMISSION);
    }
    return protectionDomains;
  }
}
