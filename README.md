security-manager
================

A custom implementation of the Java Security Manager, designed to provide extra protection and assurance for web applications.

The default Java security manager implementation is designed as a generic sandbox for untrusted code. The canonical case is running an applet on a web page. To achieve this, it checks every class on the call stack, requiring them all to have permission for any potentially-dangerous operation.

When all classes are either the Java APIs, or potentially malicious, this is a good approach. However, a typical web application has different needs and a different threat model:

- All classes can likely be enumerated in advance;
- Classes can be security-aware, not just obedient servants like the Java APIs;
- The major threats are external, eg crafted input that triggers unexpected behavior in an otherwise-trusted library.

The problem with the default approach is that the classes most exposed to attack - those at the beginning of the call stack - are also the ones that must be granted every privilege, because they are always on the call stack. This means that we cannot easily sandbox those classes.

This project aims to provide a solution, by allowing permissions further down the call stack to determine whether an action is allowed. For example, if our database access code is on the stack, then we permit network connections to our database, but if not - if, for example, someone is exploiting a vulnerability in Apache Struts and making it try to connect - then we prohibit them.

The current implementation simply looks for the *last non-system caller on the stack*. This class is assumed to be the one making the decision to perform a sensitive operation, and so its permissions are considered sufficient.

Future implementations are planned to include a new type of permission, which would act as a 'guest pass' for some other permission; that is to say, a class that holds guest permissions is permitted to be on the call stack, but there must also be a class on the stack holding the real permission in order for the operation to succeed.
