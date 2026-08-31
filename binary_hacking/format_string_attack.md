# Format String Attack

**Sources:** [https://owasp.org/www-community/attacks/Format_string_attack] and [https://cs155.stanford.edu/papers/formatstring-1.2.pdf]

**Category:** binary exploitation

## TL;DR
Attacking unchecked inputs in Format functions by inputting specifiers instead of expected input
These notes assume 32-bit architecture most of the time.
## The terminology

- **format string**: a string with containing text and placeholders like %d to format the string
- **string specifiers**: specifieres are the placeholders like %s, %d, %x, %p each for their own kind of input e.g. %s for strings
- **format functions**: functions that takes a variable number of arguments, one being a format string like printf


## The vulnerability
- **Root cause:** Format Functions are used but inpout is passed directly without usage of specifiers letting attackers insert them to read and write memory addresses
- **Vulnerable pattern:** the code shape that causes it
```c
  printf(buffer);        // bad — buffer is the format string
  printf("%s", buffer);  // fixed
```
- **Vulnerable functions/APIs:** 

Format Functions:
```
    fprintf         -       writes the printf to a file
    printf          -       outputs formatted string
    sprintf         -       prints into a string
    snprintf        -       prints into a string checking the length
    vfprintf        -       prints the va_arg structure to a file
    vprintf         -       prints the va_arg structure to stdout
    vsprintf        -       prints the va_arg structure to a string
    vsnprintf       -       prints the va_arg to a string checking the length
```
Relatives:
```
setproctile -- set argv[]
syslog -- output o the syslog facility
err*, verr*, warn*, vwarn*
```
va_arg (va_list ap, T) is a macro from stdarg.h pulling out the next argument of a variadic functions argument list (called va_list)

Suppose we got a printf like this:
```c
     printf("name %s, age %d, address %s, tom, 25, new york);
```
The values are now sitting in registers/stacks before the printf call.
printf has a loop walking through the format string. The moment it hits a specifier it calls va_arg(va_list ap, T) to grab the value at the va_list pointer and formats it according to the specifier T.

In our case va_arg(args, char*) then va_arg(args, int) and va_arg(args, char*) again. 
Each time the va_arg() macro is invocated, the va_list ap is modified to point to the next variable argument.


## Common parameters used in a Format String Attack
| Parameters | Output | Passed as |
|---|---|---|
| `%%`  | # character (ltieral) | Reference |
| `%p` | External representation of a pointer to void | Reference |
| `%d` | decimal | value |
| `%c` | character |  |
| `%u` | unsigned decimal | value|
| `%x` | hexadecimal | value
| `%s` | string | Reference
| `%n` | writes the number of chharacters into a pointer | Reference

We can use for example `%08x` instead of `%x` to singal that we want 8-digit padded hexadecimal numbers.
```c
    int i;
    printf ("foobar%n\n", (int *) &i);
    printf ("i = %d\n", i);
```
This prints i = 6. The n parameter took the bytes already there (foobar) and wrote them into the given variable i. 

Example of using `%n`:
```c
    int len = 0;
    printf("Hello, World!%n\n", &len);                          // %n writes the toal number count of everything printed SO FAR in this printf call to the pointer &len
    printf("That took %d characters to print.\n", len);         // now we print len and get the number of characters = 13

```
## Format specifier Syntax
```
%[parameter][flags][width][.precision][length]type
```
See also: [https://en.wikipedia.org/wiki/Printf]
### Parameter Field
Parameter is optional. The numeric value n, selects the n-th value parameter.
For example:
```c
printf("%2$d %2$#x; %1$d %1$#x",16,17);
```
outputs: 17 0x11; 16 0x10
This is very useful for us to find the right address when using `%p`
### Flags Field
Flags can be 0 or multiple (in any order):
```
-           left align the output of this placeholder, controlling the alignment within a padded field (purely cosmetic)
+           prepends a plus sign for a positive value (default does not show the plus sign)
<space>     prepends a space for positive value, ignored if "+ flag" exists. 
0           When "width" is specified this prepends 0s instead of spaces 
'           inserts commas every three digits (US locale), is locale dependent and not standard c. In standard c it does nothing.
#           Alternate forms (purely cosmetic):
            For g, and G types trailing zeros are removed
            For f, F, e, E, g, G the output contains a decimal point
            For o, x, X the text 0, 0x, OX is prepended to non-Zero Numbers
```

Examples:
```c
    // flags examples
    printf("%x\n", 255);         // ff
    printf("%#x\n", 255);        // 0xff
    printf("%o\n", 8);           // 10
    printf("%#o\n", 8);          // 010
    printf("%.0f\n", 3.0);       // 3
    printf("%#.0f\n", 3.0);      // 3.
```

### Width Field

Width specifies the minimum number of characters to output.
If the width field is ommited, the output is the minmum amount of characters for the value e.g. 2 if the number is 12 and 5 if the string is house.

If * is used as width, then the first argument will be used as width. This could be handy for some exploits. Basically two var_arg calls in one.

Width never truncates

```c
 // width example
    printf("Hello %4d\n", 3);        // Hello    3
    printf("Hello %04d\n", 3);       // Hello 0003
    printf("Hello %*d\n", 3, 10);    // Hello 10
    printf("Hello %*d\n", 20, 10);   // Hello                   10
    printf("%5s\n", "Hello World");  // still prints Hello World (no truncation)
```

### Precision Field

Precision does what people think width does.
```
%s	maximum characters printed — truncates the string, cuts off anything past this count

%d/%i/%u/%x/%o	minimum digit count — zero-pads the number itself (not space-padding like width does)

%f/%F/%e/%E	digits after the decimal point (default 6 if you don't specify)

%g/%G	total significant digits, not just after the decimal

%c, %p	no defined effect, generally ignored
```
Precision can be dynamic via *, also pulling the number from an argument
```c
    printf("%.2s", "abcdef");       // ab
    printf("%.*s", 3, "abcdef");    // abc
```

### Length Field

The length modifiere can be omitted. If not it comes right before the type letter

```
Modifier   | Type           | Size
(none)	   | int	        | 4 bytes
h          | short          | 2 bytes (widened to int by default promotion, but formatted as if 16-bit)
hh	       | char           | 1 byte
l          | long           | 8 bytes 
ll         | long long      | 8 bytes (standard-guaranteed ≥64-bit regardless of platform)
z          | size_t         | 8 bytes (matches pointer width)
j          | intmax_t       | widest integer type available
t          | ptrdiff_t      | 8 bytes, signed
L          | long double    | (floating point only)
```
Length changes what is displayes. Very useful to use for example `%lx` instead of `%x` to get clean looking addresses instead of truncated 32 bit addresses.

```c
    unsigned long value = 0x00000001FFFFFFFF;
    printf("%x\n", value);    // ffffffff
    printf("%lx\n", value);   // 1ffffffff
```


## Example
```c
	// This line is safe
	printf("%s\n", argv[1]);

	// This line is vulnerable
	printf(argv[1]);
```
argv[1] is the first command line argument. If we run 
```
./example "Hello World %s %s %s"
```
the first printf will just print: `Hello World %s %s %s`
the second printf will interpret `%s` as a reference to string pointers. A couple of `%s` more and it crashes with segfault.

If we use `%p`/`%x` instead we can extract information from the program in the form of hex numbers

<!--
## Mitigations / how it's normally prevented
- Compiler warnings (`-Wformat`, `-Wformat-security`)
- FORTIFY_SOURCE
- ... (whatever the page lists)

## How this applies to what I'm working on
Notes tying it back to the challenge/project at hand.

## Terms/concepts I didn't know
- **Term** — plain-English definition
-->

## Stack Example

```c 
printf ("Number %d has no address, number %d has: %08x\n", i, a, &a)
```

```
┌──────────────────┐
│  stack top       │  
├──────────────────┤
│  ...             │  
├──────────────────┤
│  <&a>            │  
├──────────────────┤
│  <a>             │
├──────────────────┤ 
│  <i>             │
├──────────────────┤ 
│  A               │
├──────────────────┤ 
│  ...             │ 
├──────────────────┤
│  stack bottom    │  
└──────────────────┘
```
```
  A   | address of the format String  
──────|─────────────────────────────
  i   | value of the variable i  
──────|─────────────────────────────
  a   | value of the variable a  
──────|─────────────────────────────
  &a  | address of the variable i  
──────|─────────────────────────────
```
That means that when printf is called the values to be parsed to the format string are stacked on top of each other in order in the stack.
First A as the address of printf then the rest. If a character is not % is is just copied to output.
To print `%`, `%%` is used.


```c 
printf("%08x.%08x.%08x.%08x.%08x\n")
```
This printf has no real argunets after the format string so each `%08x` makes var_arg grab whatever is at the next slot and prints it as 8 digit hex. so 5 times `%08x` means 5 stack slots dumped.  Same as `%p`. This reads just whatever is there on the stack. 
To read from an address of our choosing we need to change something. 
`%s` helps with that. `%s` treats the value in a slot as a pointer, goes there and reads the string sitting at that address. If we can get an address sitting in that next argument slot, `%s` would dereference it and hand it back. But how to control what is sitting in these slots?
If we input a string + enough `%x` or `%p` in a row the specifiers will basically walk through the stack printing garbage until we will eventually be returned our own String as ASCII since the buffer also lives on the stack.

Other Exploitation Example
```c
char outbuf[512];
char buffer[512];
sprintf (buffer, "ERR Wrong command: %400s", user);
sprintf (outbuf, buffer);
```
We can supply specifiers like this: `"%497d\x3c\xd3\xff\xbf<nops><shellcode>"` to circumvent the %400s limitation and override the buffer in the second `sprintf()`. 497 is chosen here because together with "ERR Wrong command:" it exceeds outbuf by 4 bytes.



## Variations of Exploitation

### Short Write

Instead of writing four times we can just write two operations through using `%n`. `%hn` to be specific, which whrites short int bytes. `h` casts the value supplied to a short type. It can also be used for other types.
Advantage of this technique: it does not destroy data besides the address, so valuable data behind the address (like function parameters) are preserved.


### Direct Parameterc Access

This means using te `$` qualifier. 
```c
printf ("%6$d\n", 6, 5, 4, 3, 2, 1);    // prints 1 because it is the 6th supplied parameter
```
A bit more difficult example:
```c
char foo[4];
printf ("%1$16u%2$n"
        "%1$16u%3$n"
        "%1$32u%4$n"
        "%1$64u%5$n",
        1,                                      // FIRST ARGUMENT
        (int *) &foo[0], (int *) &foo[1],
        (int *) &foo[2], (int *) &foo[3]);
```
`%1$16u` means argument 1 is used (here the value 1), 16 is the width - minmum field width of 16 meaning 1 is printed to the 16th positions lead by 15 spaces. <br>
`%2$n` means the second argument is used and %n stores the TOTAL number of everything printed so far (16) into it. In this case this means 16 is printed to foo[0] since the first argument is 1, the second argument is foo[0]. <br>
`%1$16u` does the same thing again. <br>
`%3$n` now prints the TOTAL number (32) to the third argument which is foo[1].<br>
`%1$32u` now takes the first argument and this time pads it with 31 spaces. <br>
`%4$n` now print that total number (64) to the fourth argument to foo[2]. <br>
`%1$64u` now takes the first argument and this time pad it with 63 spaces. <br>
`%5$n` now print that total number to the fifth argument to foo[3].




### Bruteforcing

Finding the right offset is crucial for buffer overflows. With simple problems guessing or bruteforcing works, but with more complex problems you might need multiple offsets and this increases the complexity of the problem exponentially. So brute forcing does not work anymore. 
A format string bug gives us read and write, so we are not blind as with buffer overflow (either program crashes or we are successful). So sending harmless tests and reading the answer gives us valueable information. For this to be true we need to be able to se send more than one format string and see a response each try.


####  Response Based Brute Force
The simple kind of brute force. Input looks like this: `"AAAABBBB|stackpop|%08x|"`
replace stackpop with the distance to guess. Increase on every try:
```c
  while (distance > 0) {
        strcat (stackpop, "%u");                  // every %u (unsigned decimal integer) is 4 bytes so we increase the distance incrementaly
        distance -= 4;                       
}
```
A distance of 32 would look like this: `"AAAABBBB|%u%u%u%u%u%u%u%u|%08x|"` popping 32 bytes from the stack and printing the four bytes after in hex. If that is the successful try, the output would look like this: `AAAABBBB|983217938177639561760134608728913021|41414141|`. 41414141 is the hex representation of AAAA. Usually you should be able to reach this pattern at some distance. If you can not there could be two reason: <br>
1. the distance is too big, like if the string is located on the heap
2. or the alignment is not on a four byte binary. In the latter case we have to prepend the format string with one to three dummy bytes. If we use ABCD as input it is a bit easier to see the alignment is wrong. Alignment is important so %N$n can write to the correct adress we control instead of garbage + our input

Once you know the exact alignment and distance `addr|stackpop|______________________________%%|%s|` does the trick. The string is processed left to right, `%s` will print the ASCII string from addr.

The ideal guess lands us in our own buffer so `%s` prints back part of our own input. That is what `%%` does. It marks our own buffer. Two `%` characters means we landed in our own format string, only one means we accidently hit some other buffer. Now we know exactly where our buffer lives in the memory and use it to calculate other addresses relative to it. 

#### Blind Brute Forcing

Not as easy to do step by step. We can measure the time it takes to process format strings `“%.9999999u”` takes longer than `%u` and we can produce segfaults by using `%n` on unmapped addresses. Can be found in the example/ directory of the paper. 



## Learnings
- the simplest attack is just supplying these vulnerable format strings with endless `%s` to crash the program. This can be useful to crash a daemon that dumps core to then take a look at it within the coredump. Or to deny a web server for example when DNS spoofing.
## Questions / things to look up next
- https://cs155.stanford.edu/papers/formatstring-1.2.pdf
- what exactly are the addresses `%p` gives us as information
