package id.antuar.carl.security;

import org.junit.Test;

import java.security.AllPermission;

import static org.junit.Assert.*;

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

  @Test(expected = SecurityException.class)
  public void shouldThrowSecurityExceptionForUnprivilegedCode() {
    new CallerBasedSecurityManager().checkPermission(new AllPermission());
  }

  private static class NonSystemClass {}

}
