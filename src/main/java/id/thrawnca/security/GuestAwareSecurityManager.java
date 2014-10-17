package id.thrawnca.security;

import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Collection;
import java.util.Map;
import java.util.HashSet;

/**
 * A security manager implementation that is aware of GuestPass permissions.
 * The holder of a guest pass is allowed to be on the call stack for the
 * wrapped permission, iff there is a non-system class on the stack
 * holding the real permission.
 * @author Carl Antuar
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class GuestAwareSecurityManager
  extends AbstractCustomSecurityManager {

  /**
   * Walk the call stack, recognising the presence of guest-pass holders.
   * Fail if guests are found and no-one has the real permission,
   * or if someone has no relevant permission at all.
   * @param perm The permission needed.
   * @param callStack The call stack to check.
   * @param protectionDomains The protection domains for the call stack.
   */
  // PMD-Controversial doesn't like what we're doing here,
  // but it's hard to please.
  @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
  @Override
  protected void checkPermissionForContext(
      final Permission perm,
      final Class[] callStack,
      final Map<Class, ProtectionDomain> protectionDomains) {
    final Collection<Class> guests = new HashSet<Class>();
    boolean realPresent = false;
    final GuestPass guestPass = new GuestPass(perm);
    for (int i = 0; i < callStack.length; i++) {
      final Class caller = callStack[i];
      final ProtectionDomain domain = protectionDomains.get(caller);
      /*
       * Holders of AllPermission are either system classes,
       * which do whatever they're told, or else someone was lazy.
       * Either way, their permissions are respected for themselves,
       * but they don't authorise guests.
       */
      if (!isSystemClass(caller)) {
        if (domain.implies(perm)) {
          realPresent = true;
        } else if (domain.implies(guestPass)) {
          guests.add(caller);
        } else {
          handleFailure(perm, caller);
        }
      }
    }
    if (!realPresent && !guests.isEmpty()) {
      handleFailure(perm, guests.toArray(new Class[guests.size()]));
    }
  }

}
