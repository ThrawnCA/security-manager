package id.thrawnca.security;

import org.testng.annotations.Test;

import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Map;

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

  /** The permission needed to replace the security manager. */
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
  @Test
  public void shouldThrowSecurityExceptionWhenInstalled() {
    System.setSecurityManager(manager);
    try {
      manager.checkPermission(AbstractCustomSecurityManager.ALL_PERM);
      fail("Should not have granted AllPermission when installed");
    } catch (SecurityException e) {
      assertTrue(e.getMessage().contains("access denied"),
        "Expected 'access denied' but instead saw: " + e.getMessage()
      );
    } finally {
      System.setSecurityManager(null);
    }
  }

  // Tests with SecurityContext

  /**
   * Ensure that exception is not thrown for permission we don't have
   * when called with a security context
   * and the security manager is not installed.
   */
  @Test
  public void shouldNotThrowSecurityExceptionWithContextWhenNotInstalled() {
    try {
      manager.checkPermission(
        AbstractCustomSecurityManager.ALL_PERM,
        SecurityManagerPermissionsTest.getSecurityContext(getClass())
      );
    } catch (SecurityException e) {
      fail("Should not have thrown security exception when not installed");
    }
  }

  /**
   * Ensure that a security exception is thrown
   * when the security manager is installed
   * and we are using a security context of the wrong type.
   */
  @Test
  public void shouldThrowExceptionForWrongContextTypeWhenInstalled() {
    System.setSecurityManager(manager);
    try {
      manager.checkPermission(new TestPermission("granted"), new Object());
      fail("Should not have granted permission for invalid security context");
    } catch (SecurityException e) {
      assertTrue(e.getMessage().contains("Wrong security context type"),
        "Expected 'wrong type' but instead saw: " + e.getMessage()
      );
    } finally {
      System.setSecurityManager(null);
    }
  }

  /**
   * Ensure that a security exception is not thrown
   * when the security manager is not installed
   * even if we are using a security context of the wrong type.
   */
  @Test
  public void shouldNotThrowExceptionForWrongContextTypeWhenNotInstalled() {
    try {
      manager.checkPermission(new TestPermission("granted"), new Object());
    } catch (SecurityException e) {
      fail("Should not have thrown security exception when not installed");
    }
  }

  /**
   * Test security manager that always fails.
   * @author Carl Antuar
   */
  public static final class FailingSecurityManager
    extends AbstractCustomSecurityManager {

    /**
     * The permission needed to replace/remove the security manager.
     * This is a reference to the instance in the outer class
     * in order to ensure that the outer class file is loaded eagerly.
     */
    private static final Permission ALLOWED_PERM = SET_SECURITY;

    /**
     * Calls the handleFailure method with the whole call stack,
     * except when replacing/removing the security manager.
     * @param perm The permission being checked.
     * @param callStack The call stack to check.
     * @param protectionDomains The protection domains for the call stack.
     */
    @Override
    protected void checkPermissionForContext(
        final Permission perm,
        final Class[] callStack,
        final Map<Class, ProtectionDomain> protectionDomains) {
      if (!ALLOWED_PERM.equals(perm)) {
        handleFailure(perm, callStack);
      }
    }
  }

}
