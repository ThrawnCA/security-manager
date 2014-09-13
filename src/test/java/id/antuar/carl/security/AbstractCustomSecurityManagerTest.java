package id.antuar.carl.security;

import org.junit.After;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.AllPermission;
import java.security.Permission;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Ensure, as much as possible, that the CallerBasedSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
public final class AbstractCustomSecurityManagerTest {

  /**
   * Wipe out any security manager configuration.
   */
  @After
  public void tearDown() {
    System.setSecurityManager(null);
    System.clearProperty(AbstractCustomSecurityManager.LOG_PROPERTY);
  }

  /**
   * Ignore standard Java APIs since they don't initiate actions.
   */
  @SuppressWarnings("PMD.JUnitTestsShouldIncludeAssert")
  @Test
  public void shouldDetectJavaAPIAsSystemClass() {
    checkSystemClass(Object.class, true);
  }

  /**
   * Ignore internal JVM classes since they are basically like the APIs.
   */
  @Test
  public void shouldDetectJVMInternalClassAsSystemClass() {
    try {
      checkSystemClass(Class.forName("sun.misc.BASE64Decoder"), true);
    } catch (ClassNotFoundException e) {
      fail("Unknown JVM. Adapt the security manager before using it!");
    }
  }

  /**
   * Check a generic non-system class that we provide.
   */
  @SuppressWarnings("PMD.JUnitTestsShouldIncludeAssert")
  @Test
  public void shouldDetectOrdinaryClassAsNonSystemClass() {
    checkSystemClass(getClass(), false);
  }

  /**
   * Helper for methods that test the 'isSystemClass' method.
   * @param clazz The class to check.
   * @param expectSystem Whether or not 'clazz'
   * should be treated as a system class.
   */
  private static void checkSystemClass(final Class clazz,
                                       final boolean expectSystem) {
    assertEquals(
      String.format("%s to be treated as system class:", clazz.getName()),
      expectSystem,
      AbstractCustomSecurityManager.isSystemClass(clazz)
    );
  }

  /**
   * Check the security bypass for privileged code.
   */
  @Test
  public void shouldBypassSecurityToCheckPermissions() {
    System.setSecurityManager(new CallerBasedSecurityManager());
    assertFalse("Test should not have AllPermission",
      AbstractCustomSecurityManager.implies(
        getClass(), CallerBasedSecurityManager.ALL_PERM
      )
    );
  }

  /**
   * Ensure no exception happens in log mode.
   * @exception UnsupportedEncodingException Should never happen for UTF-8.
   */
  @Test
  public void shouldNotThrowSecurityExceptionInLogMode()
    throws UnsupportedEncodingException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    System.setErr(new PrintStream(baos, true, "UTF-8"));
    System.setProperty(CallerBasedSecurityManager.LOG_PROPERTY, "");
    new FailingSecurityManager().checkPermission(new AllPermission());
    assertTrue("Expected permission to be logged",
      new String(baos.toByteArray(), "UTF-8")
        .contains(AllPermission.class.getName())
    );
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
