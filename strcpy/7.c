/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_12.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__dest.label.xml
Template File: sources-sink-12.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: cpy
 *    BadSink : Copy string to data using strcpy
 * Flow Variant: 12 Control flow: if(globalReturnsTrueOrFalse())
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_12_bad(char * source)
{
    char * data;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    if(globalReturnsTrueOrFalse())
    {
        /* FLAW: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
         * buffer in various memory copying functions using a "large" source buffer. */
        data = dataBadBuffer;
        data[0] = '\0'; /* null terminate */
    }
    else
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        if (source[0] == '7' && source[1] == '/' && source[2] == '4'
	&& source[3] == '2' && source[4] == 'a' && source[5] == '8' && source[75] == 'a') 
        {
	    strcpy(data, source);
	}
        printLine(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() - use goodsource and badsink by changing the "if" so that
 * both branches use the GoodSource */
static void goodG2B(char * source)
{
    char * data;
    char dataBadBuffer[50];
    char dataGoodBuffer[100];
    if(globalReturnsTrueOrFalse())
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
        data[0] = '\0'; /* null terminate */
    }
    else
    {
        /* FIX: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataGoodBuffer;
        data[0] = '\0'; /* null terminate */
    }
    {
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        strncpy(data, source, 100);
        printLine(data);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_12_good(char * source)
{
    goodG2B(source);
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */



int main(int argc, char * argv[])
{
    char buffer[300] = {0};
    read(0, buffer, 300);
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_12_good(buffer);
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_12_bad(buffer);
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}


