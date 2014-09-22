security-manager
================

A custom implementation of the Java Security Manager, designed to provide extra protection and assurance for web applications. It allows the use of more flexible permission algorithms to better suit the security needs of a J2EE environment.

The problem
===========

The default Java security manager implementation is designed as a generic sandbox for untrusted code; the canonical case is running an applet on a web page. To achieve this, it checks every class on the call stack, requiring them all to have permission for any potentially-dangerous operation. When all classes are either the Java APIs (trusted), or arbitrary potentially-malicious code (untrusted), this is a good approach. However, a typical web application has different needs and a different threat model:

- All classes can likely be enumerated in advance;
- Classes can be security-aware, not just obedient servants like the Java APIs;
- The major threats are external, eg crafted input that triggers unexpected behavior in an otherwise-trusted library.

The problem with the default approach is that the classes most exposed to attack - those at the beginning of the call stack, like the application server itself - are also the ones that must be granted every privilege, because they are always on the call stack. This means that we cannot easily sandbox those classes. What we need is for their privileges to be based on context, not just granted/forbidden.

The solution
============

This project provides custom security manager algorithms to help improve the situation, by allowing permissions elsewhere on the call stack to determine whether an action is allowed. For example, if our database access code is on the stack, then we permit network connections to our database, but if not - if, for example, someone is exploiting a vulnerability in Apache Struts and making it try to connect - then we prohibit them.

The CallerBasedSecurityManager implementation simply looks for the *last non-system caller on the stack*. This class is assumed to be the one making the decision to perform a sensitive operation, and so its permissions are considered sufficient. This implementation is simple, and potentially suitable for a J2EE application, but has the weakness that unknown code could exploit the privileges granted to trusted code. It would certainly not be suitable for running applets.

The GuestAwareSecurityManager implementation, on the other hand, recognises a new type of permission, which acts as a 'guest pass' for some other permission; that is to say, a class that holds guest permissions is permitted to be on the call stack, but there must also be a class on the stack holding the real permission in order for the operation to succeed. Guest passes are a strictly weaker permission than real permissions, and so this implementation is potentially more secure than the default one. Typical usage would involve granting a very broad guest pass, eg GuestPass(AllPermission), to system code such as the application server, and then specific real permissions to the deployed application. As long as the application is behaving normally, this will behave much like real permissions; however, the application server will not be permitted to act independently.

Future plans
============

Version 2 is planned to involve a pluggable architecture, where multiple security strategies are applied. The two current implementations would both be available as strategies, but it would also be possible to include others, eg a strategy that blacklists certain permissions that we know a particular application does not need, and refuses to grant them even to classes holding AllPermission; or a strategy that recognises permissions granted only to a single class, not to an entire protection domain.
