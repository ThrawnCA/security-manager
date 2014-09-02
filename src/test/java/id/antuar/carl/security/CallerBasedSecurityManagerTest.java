package id.antuar.carl.security;

import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
  @Test
  public final void shouldDetectJavaAPIAsSystemClass() {
    assertTrue(CallerBasedSecurityManager.isSystemClass(Object.class));
  }

  /**
   * Ignore internal JVM classes since they are basically like the APIs.
   */
  @Test
  public final void shouldDetectJVMInternalClassAsSystemClass() {
    Class clazz;
    try {
      clazz = Class.forName("sun.misc.BASE64Decoder");
      assertTrue(CallerBasedSecurityManager.isSystemClass(clazz));
    } catch (ClassNotFoundException e) {
      try {
        clazz = Class.forName("com.jrockit.mc.rjmx.flr.internal.ContentTypes");
        assertTrue(CallerBasedSecurityManager.isSystemClass(clazz));
      } catch (ClassNotFoundException e2) {
        fail("Unknown JVM. Adjust the security manager before using it!");
      }
    }
  }

  /**
   * Check a generic non-system class that we provide.
   */
  @Test
  public final void shouldDetectOrdinaryClassAsNonSystemClass() {
    assertFalse(CallerBasedSecurityManager.isSystemClass(NonSystemClass.class));
  }

  /**
   * The last non-system caller, when we ask, should be ourselves.
   */
  @Test
  public final void shouldDetectLastNonSystemCaller() {
    assertSame(
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
   * Test policy does permit writing temporary files.
   * @exception IOException Shouldn't happen, but if it does, then fail.
   */
  @Test
  public final void shouldNotThrowSecurityExceptionForPrivilegedCode()
      throws IOException {
    File.createTempFile("test", null).deleteOnExit();
  }

  /**
   * A generic class that should not be detected as a system class.
   */
  private static class NonSystemClass { }

}
