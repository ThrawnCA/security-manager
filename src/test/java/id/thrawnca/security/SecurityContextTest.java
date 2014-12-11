package id.thrawnca.security;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Check whether SecurityContext correctly protects itself against tampering.
 *
 * @author Carl Antuar
 */
public final class SecurityContextTest {

  /** Singleton security manager. */
  private final AbstractCustomSecurityManager manager;

  /**
   * Construct a singleton security manager for use in tests.
   */
  public SecurityContextTest() {
    manager = new AbstractCustomSecurityManagerTest.FailingSecurityManager();
  }

  /**
   * Ensure that the permission system has been loaded properly.
   * Also ensures that necessary class files are loaded
   * before installing the always-fail security manager.
   */
  @BeforeClass
  public static void ensureSetUp() {
    assertFalse(
      SecurityContextTest.class.getProtectionDomain().implies(
        SecurityContext.CLASS_PERMISSION
      ), "Test should not have permission to retrieve call stack"
    );
    assertTrue(
      SecurityContextTest.class.getProtectionDomain().implies(
        AbstractCustomSecurityManagerTest.SET_SECURITY
      ), "'setSecurityManager' permission not loaded correctly"
    );
  }

  /**
   * Ensure that accessing the call stack requires privileges.
   */
  @Test
  public void shouldProtectCallStackAgainstRetrieval() {
    try {
      System.setSecurityManager(manager);
      ((SecurityContext) manager.getSecurityContext()).getClassContext();
      fail("Should have prevented unprivileged access to call stack");
    } catch (SecurityException e) {
      assertTrue(e.getMessage().contains("access denied"),
        "Expected 'access denied' but instead saw: " + e.getMessage()
      );
    } finally {
      System.setSecurityManager(null);
    }
  }

  /**
   * Ensure that accessing the protection domains requires privileges.
   */
  @Test
  public void shouldProtectProtectionDomainsAgainstRetrieval() {
    try {
      System.setSecurityManager(manager);
      ((SecurityContext) manager.getSecurityContext()).getProtectionDomains();
      fail("Should have prevented unprivileged access to protection domains");
    } catch (SecurityException e) {
      assertTrue(e.getMessage().contains("access denied"),
        "Expected 'access denied' but instead saw: " + e.getMessage()
      );
    } finally {
      System.setSecurityManager(null);
    }
  }

  /**
   * Ensure that accessing the protection domains is allowed
   * when no security manager is installed.
   */
  @Test
  public void shouldNotProtectProtectionDomainsWhenNoSecurityManager() {
    try {
      ((SecurityContext) manager.getSecurityContext()).getProtectionDomains();
    } catch (SecurityException e) {
      fail("Expected to grant access when no security manager installed");
    }
  }

  /**
   * Ensure that accessing the call stack is allowed
   * when no security manager is installed.
   */
  @Test
  public void shouldNotProtectCallStackWhenNoSecurityManager() {
    try {
      ((SecurityContext) manager.getSecurityContext()).getClassContext();
    } catch (SecurityException e) {
      fail("Expected to grant access when no security manager installed");
    }
  }

}
