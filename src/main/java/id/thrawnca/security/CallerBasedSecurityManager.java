package id.thrawnca.security;

import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Map;

/**
 * This SecurityManager checks the most recent non-system class
 * on the call stack, instead of every class.
 *
 * @author Carl Antuar
 */
public class CallerBasedSecurityManager extends AbstractCustomSecurityManager {

  /**
   * @param callStack The call stack being examined.
   * @return The most recent non-system class on the call stack,
   * excluding the security manager itself.
   */
  protected static Class getLastCaller(final Class... callStack) {
    Class lastCaller = null;
    for (int i = 0; lastCaller == null && i < callStack.length; i++) {
      if (!isSystemClass(callStack[i])) {
        lastCaller = callStack[i];
      }
    }
    return lastCaller;
  }

  /**
   * Checks whether the most recent non-system class on the stack
   * has the specified permission.
   * @param perm The permission needed.
   * @param callStack The call stack to check.
   * @param protectionDomains The protection domains for the call stack.
   */
  @Override
  protected final void checkPermissionForContext(
      final Permission perm,
      final Class[] callStack,
      final Map<Class, ProtectionDomain> protectionDomains) {
    final Class clazz = getLastCaller(callStack);
    if (clazz != null && !protectionDomains.get(clazz).implies(perm)) {
      handleFailure(perm, clazz);
    }
  }

}
