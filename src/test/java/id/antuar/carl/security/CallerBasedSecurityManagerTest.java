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

  @Test
  public void shouldDetectJavaAPIAsSystemClass() {
    assertTrue(CallerBasedSecurityManager.isSystemClass(java.lang.Object.class));
  }

  @Test
  public void shouldDetectJVMInternalClassAsSystemClass() {
    try {
      assertTrue(CallerBasedSecurityManager.isSystemClass(Class.forName("sun.misc.BASE64Decoder")));
    } catch (ClassNotFoundException e) {
      try {
        assertTrue(CallerBasedSecurityManager.isSystemClass(Class.forName("com.jrockit.mc.rjmx.flr.internal.ContentTypes")));
      } catch (ClassNotFoundException e2) {
        fail("Unknown JVM. Please update the list of internal package names in CallerBasedSecurityManager before using it!");
      }
    }
  }

  @Test
  public void shouldDetectOrdinaryClassAsNonSystemClass() {
    assertFalse(CallerBasedSecurityManager.isSystemClass(NonSystemClass.class));
  }

  @Test
  public void shouldDetectLastNonSystemCaller() {
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
