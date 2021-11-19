#include <clang-c/Index.h>  // This is libclang.
#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "sgx_tprotected_fs.h"
#include "sgx_tseal.h"
#include <stdlib.h>

void ecall_analyze_file(void* ptr, size_t len) {

    CXUnsavedFile f = {};
    f.Filename = "test.cpp";
    f.Contents = (char *)ptr;
    f.Length = len;
    CXIndex index = clang_createIndex(0, 0);
    CXTranslationUnit unit = clang_parseTranslationUnit(
      index,
      nullptr,
      nullptr,
      0,
      &f,
      1,
      CXTranslationUnit_None);
    if (unit == nullptr)
    {
      printf("Unable to parse translation unit. Quitting.");
      return;
    }

    // CXCursor cursor = clang_getTranslationUnitCursor(unit);
    // clang_visitChildren(
    //   cursor,
    //   [](CXCursor c, CXCursor parent, CXClientData client_data)
    //   {
    //     printf("Cursor %s of kind %s\n", clang_getCursorSpelling(c), clang_getCursorKindSpelling(clang_getCursorKind(c)));
    //     return CXChildVisit_Recurse;
    //   },
    //   nullptr);
    //
    // clang_disposeTranslationUnit(unit);
    // clang_disposeIndex(index);

    printf("done");
}

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);

    ocall_print_string(buf);
    return 0;
}
