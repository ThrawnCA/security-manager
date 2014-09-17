package id.thrawnca.security;

import java.security.Permission;

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
    int startIndex = 0;
    while (callStack[startIndex] == CallerBasedSecurityManager.class
      || callStack[startIndex] == AbstractCustomSecurityManager.class) {
      startIndex++;
    }
    for (int i = startIndex; lastCaller == null && i < callStack.length; i++) {
      if (!isSystemClass(callStack[i])) {
        lastCaller = callStack[i];
      }
    }
    return lastCaller;
  }

  /**
   * Checks whether the most recent non-system class on the stack
   * has the specified permission.
   * @param callStack The call stack to check.
   * @param perm The permission needed.
   */
  @Override
  protected final void checkPermission(final Class[] callStack,
                                       final Permission perm) {
    final Class clazz = getLastCaller(callStack);
    if (clazz != null && !implies(clazz, perm)) {
      handleFailure(clazz, perm);
    }
  }

}
