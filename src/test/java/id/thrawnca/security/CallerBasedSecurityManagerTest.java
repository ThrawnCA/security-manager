package id.thrawnca.security;

import org.testng.annotations.Test;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;

/**
 * Ensure, as much as possible, that the CallerBasedSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
public final class CallerBasedSecurityManagerTest {

  /** Convenience string for permission name that is granted to tests. */
  public static final String GRANTED = "granted";

  /** Convenience string for permission name that is not granted to tests. */
  public static final String NOT_GRANTED = "notGranted";

  /** Singleton security manager. */
  private final CallerBasedSecurityManager manager;

  /**
   * Construct a singleton security manager for use in tests.
   */
  public CallerBasedSecurityManagerTest() {
    manager = new CallerBasedSecurityManager();
  }

  /**
   * Ensure that the last non-system caller is correctly detected.
   */
  @Test
  public void shouldDetectLastNonSystemCaller() {
    final Class<?> managerClass = manager.getClass();
    final Class<?> testClass = CallerBasedSecurityManagerTest.class;
    final Class<?> systemClass = Object.class;
    assertSame(
      CallerBasedSecurityManager.getLastCaller(
        managerClass,
        managerClass,
        systemClass,
        managerClass,
        testClass
      ),
      managerClass,
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

}
