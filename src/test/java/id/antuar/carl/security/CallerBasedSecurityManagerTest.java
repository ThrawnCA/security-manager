package id.antuar.carl.security;

import org.junit.Assert;
import org.junit.Test;

/**
 * Ensure, as much as possible, that the CallerBasedSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
public class CallerBasedSecurityManagerTest {

  /**
   * Ignore standard Java APIs since they don't initiate actions.
   */
  @SuppressWarnings("PMD.JUnitTestsShouldIncludeAssert")
  @Test
  public final void shouldDetectJavaAPIAsSystemClass() {
    checkSystemClass(Object.class, true);
  }

  /**
   * Ignore internal JVM classes since they are basically like the APIs.
   */
  @Test
  public final void shouldDetectJVMInternalClassAsSystemClass() {
    String className;
    try {
      className = "sun.misc.BASE64Decoder";
      checkSystemClass(Class.forName(className), true);
    } catch (ClassNotFoundException e) {
      try {
        className = "com.jrockit.mc.rjmx.flr.internal.ContentTypes";
        checkSystemClass(Class.forName(className), true);
      } catch (ClassNotFoundException e2) {
        Assert.fail("Unknown JVM. Adapt the security manager before using it!");
      }
    }
  }

  /**
   * Check a generic non-system class that we provide.
   */
  @SuppressWarnings("PMD.JUnitTestsShouldIncludeAssert")
  @Test
  public final void shouldDetectOrdinaryClassAsNonSystemClass() {
    checkSystemClass(NonSystemClass.class, false);
  }

  /**
   * Helper for methods that test the 'isSystemClass' method.
   * @param clazz The class to check.
   * @param expectSystem Whether or not 'clazz'
   * should be treated as a system class.
   */
  private static void checkSystemClass(final Class clazz,
                                       final boolean expectSystem) {
    Assert.assertEquals(
      String.format("%s to be treated as system class:", clazz.getName()),
      expectSystem,
      CallerBasedSecurityManager.isSystemClass(clazz)
    );
  }

  /**
   * The last non-system caller, when we ask, should be ourselves.
   */
  @Test
  public final void shouldDetectLastNonSystemCaller() {
    Assert.assertSame(
      CallerBasedSecurityManager.getLastCaller(
        CallerBasedSecurityManager.class,
        Object.class,
        CallerBasedSecurityManagerTest.class,
        java.io.FileOutputStream.class
      ),
      CallerBasedSecurityManagerTest.class
    );
  }

  /**
   * Test policy does not permit changing system properties.
   */
  @Test(expected = SecurityException.class)
  public final void shouldThrowSecurityExceptionForUnprivilegedCode() {
    System.setProperty("java.io.tmpdir", "foo");
  }

  /**
   * Test policy does permit reading system properties.
   */
  @Test
  public final void shouldNotThrowSecurityExceptionForPrivilegedCode() {
    Assert.assertFalse("Expected to retrieve temporary directory",
      System.getProperty("java.io.tmpdir").isEmpty()
    );
  }

  /**
   * A generic class that should not be detected as a system class.
   */
  private static class NonSystemClass { }

}
