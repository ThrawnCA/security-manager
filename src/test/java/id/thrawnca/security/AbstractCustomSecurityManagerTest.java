package id.thrawnca.security;

import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.Permission;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Ensure, as much as possible, that the CallerBasedSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class AbstractCustomSecurityManagerTest {

  /**
   * Ignore any class that has been granted AllPermission,
   * since we assume that it is a system class.
   */
  @Test
  public void shouldDetectSystemClass() {
    assertTrue(AbstractCustomSecurityManager.isSystemClass(Object.class),
      "Object treated as a system class");
  }

  /**
   * Check a non-system class (this one).
   */
  @Test
  public void shouldDetectOrdinaryClassAsNonSystemClass() {
    assertFalse(AbstractCustomSecurityManager.isSystemClass(getClass()),
      getClass().getName() + " treated as a system class");
  }

  /**
   * Check the security bypass for privileged code.
   */
  @Test
  public void shouldBypassSecurityToCheckPermissions() {
    System.setSecurityManager(new CallerBasedSecurityManager());
    try {
      assertFalse(
        AbstractCustomSecurityManager.implies(
          getClass(), CallerBasedSecurityManager.ALL_PERM
        ), "Test should not have AllPermission"
      );
    } finally {
      System.setSecurityManager(null);
    }
  }

  /**
   * Ensure no exception happens in log mode.
   * @exception UnsupportedEncodingException Should never happen for UTF-8.
   */
  @Test
  public void shouldNotThrowSecurityExceptionInLogMode()
    throws UnsupportedEncodingException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    final PrintStream realStdErr = System.err;
    try {
      System.setErr(new PrintStream(baos, true, "UTF-8"));
      System.setProperty(CallerBasedSecurityManager.LOG_PROPERTY, "");
      new FailingSecurityManager()
        .checkPermission(AbstractCustomSecurityManager.ALL_PERM);
      assertTrue(
        new String(baos.toByteArray(), "UTF-8").contains(
          AbstractCustomSecurityManager.ALL_PERM.getClass().getName()
        ), "Expected permission to be logged"
      );
    } finally {
      System.setErr(realStdErr);
      System.clearProperty(AbstractCustomSecurityManager.LOG_PROPERTY);
    }
  }

  /**
   * Test security manager that always fails.
   * @author Carl Antuar
   */
  private static final class FailingSecurityManager
    extends AbstractCustomSecurityManager {
    /**
     * Calls the handleFailure method with the first class on the stack.
     * @param callStack The call stack to check.
     * @param perm The permission being checked.
     */
    @Override
    protected void checkPermission(final Class[] callStack,
                                   final Permission perm) {
      handleFailure(callStack[0], perm);
    }
  }

}
