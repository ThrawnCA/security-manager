package id.antuar.carl.security;

import org.testng.annotations.Test;

import java.security.Permission;
import java.util.PropertyPermission;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.fail;

/**
 * Ensure, as much as possible, that the CallerBasedSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class CallerBasedSecurityManagerTest {

  /**
   * The last non-system caller, when we ask, should be ourselves.
   */
  @Test
  public void shouldDetectLastNonSystemCaller() {
    final Class<?> manager = CallerBasedSecurityManager.class;
    final Class<?> test = CallerBasedSecurityManagerTest.class;
    final Class<?> system = Object.class;
    assertSame(
      CallerBasedSecurityManager.getLastCaller(
        manager,
        manager,
        system,
        manager,
        test
      ),
      manager,
      "Wrong caller identified"
    );
  }

  /**
   * Completely-privileged stacks should be ignored.
   */
  @Test
  public void shouldReturnNullForAllSystemStack() {
    assertNull(
      CallerBasedSecurityManager.getLastCaller(
        Object.class,
        Object.class,
        Object.class
      ), "No caller expected for all-system stack"
    );
  }

  /**
   * Ensure that exception is thrown for permission we don't have.
   */
  @Test(expectedExceptions = SecurityException.class)
  public void shouldThrowSecurityExceptionForUnprivilegedCode() {
    final Permission perm = new PropertyPermission("java.io.tmpdir", "write");
    new CallerBasedSecurityManager().checkPermission(perm);
    fail("Should have failed to alter system temporary directory");
  }

  /**
   * Test policy permits reading system properties.
   */
  @Test
  public void shouldNotThrowSecurityExceptionForPrivilegedCode() {
    final Permission perm = new PropertyPermission("java.io.tmpdir", "read");
    try {
      new CallerBasedSecurityManager().checkPermission(perm);
    } catch (SecurityException e) {
      fail("Expected permission " + perm + " to be granted");
    }
  }

  /**
   * Completely-privileged stacks should be ignored.
   */
  @Test
  public void shouldNotThrowSecurityExceptionForSystemCode() {
    final Permission perm = new PropertyPermission("java.io.tmpdir", "read");
    try {
      new CallerBasedSecurityManager().checkPermission(
        new Class<?>[] {
          Object.class, Object.class, Object.class
        }
        , perm
      );
    } catch (SecurityException e) {
      fail("System code should be ignored");
    }
  }

}
