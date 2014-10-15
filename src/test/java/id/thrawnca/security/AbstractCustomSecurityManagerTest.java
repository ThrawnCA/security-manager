package id.thrawnca.security;

import org.testng.annotations.Test;

import java.security.Permission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Ensure, as much as possible, that the AbstractCustomSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
public final class AbstractCustomSecurityManagerTest {

  /** The only thing the failing security manager allows is its replacement. */
  public static final Permission SET_SECURITY =
    new RuntimePermission("setSecurityManager");

  /** Sample security manager that always fails. */
  private final AbstractCustomSecurityManager manager;

  /**
   * Construct a failing security manager for use in tests
   * that should not fail.
   */
  public AbstractCustomSecurityManagerTest() {
    manager = new FailingSecurityManager();
  }

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
   * Check that the security manager itself
   * is stripped from the call stack.
   */
  @Test
  public void shouldTrimSecurityManagerFromCallStack() {
    assertEquals(
      manager.trimCallStack(
        Object.class,
        SecurityManager.class,
        AbstractCustomSecurityManager.class,
        FailingSecurityManager.class,
        AbstractCustomSecurityManagerTest.class
      ),
      new Class[] {AbstractCustomSecurityManagerTest.class},
      "Should have trimmed security manager and parent classes from stack"
    );
  }

  /**
   * Ensure no exception happens in log mode.
   */
  @Test
  public void shouldNotThrowSecurityExceptionInLogMode() {
    System.setProperty(AbstractCustomSecurityManager.LOG_PROPERTY, "true");
    final SecurityManager newManager = new FailingSecurityManager();
    try {
      System.setSecurityManager(newManager);
      newManager.checkPermission(AbstractCustomSecurityManager.ALL_PERM);
    } catch (SecurityException e) {
      fail("Should not have thrown exception in log mode", e);
    } finally {
      System.setSecurityManager(null);
      System.clearProperty(AbstractCustomSecurityManager.LOG_PROPERTY);
    }
  }

  /**
   * Ensure that exception is not thrown for permission we don't have
   * when the security manager is not installed.
   */
  @Test
  public void shouldNotThrowSecurityExceptionWhenNotInstalled() {
    try {
      manager.checkPermission(AbstractCustomSecurityManager.ALL_PERM);
    } catch (SecurityException e) {
      fail("Should not have thrown security exception when not installed");
    }
  }

  /**
   * Ensure that exception is thrown for permission we don't have
   * when the security manager is properly installed.
   */
  @Test(expectedExceptions = SecurityException.class)
  public void shouldThrowSecurityExceptionWhenInstalled() {
    System.setSecurityManager(manager);
    try {
      manager.checkPermission(AbstractCustomSecurityManager.ALL_PERM);
      fail("Should not have granted AllPermission when installed");
    } finally {
      System.setSecurityManager(null);
    }
  }

  /**
   * Test security manager that always fails.
   * @author Carl Antuar
   */
  public static final class FailingSecurityManager
    extends AbstractCustomSecurityManager {

    /**
     * Calls the handleFailure method with the whole call stack.
     * @param callStack The call stack to check.
     * @param perm The permission being checked.
     */
    @Override
    protected void checkPermission(
        final Permission perm,
        final Class[] callStack
      ) {
      if (!SET_SECURITY.equals(perm)) {
        handleFailure(perm, callStack);
      }
    }
  }

}
