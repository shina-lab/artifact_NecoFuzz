#pragma once
/** ***************************************************************************
 * @section section_uefi Section 1. UEFI definitions
 * This section contains several basic UEFI type and function definitions.
 *************************************************************************** */
#include <stdint.h>

#define IN
#define OUT
#define EFIAPI

typedef unsigned short CHAR16, UINT16;
typedef unsigned long long EFI_STATUS;
typedef void* EFI_HANDLE;

static const EFI_STATUS EFI_SUCCESS = 0;
static const EFI_STATUS EFI_NOT_READY = 0x8000000000000006;

struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct {
  UINT16 ScanCode;
  CHAR16 UnicodeChar;
} EFI_INPUT_KEY;
typedef EFI_STATUS(EFIAPI* EFI_INPUT_READ_KEY)(
    IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL* This,
    OUT EFI_INPUT_KEY* Key);
struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
  void* a;
  EFI_INPUT_READ_KEY ReadKeyStroke;
};

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef EFI_STATUS(EFIAPI* EFI_TEXT_STRING)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* This,
    IN CHAR16* String);
struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
  void* a;
  EFI_TEXT_STRING OutputString;
};

typedef struct {
  char a[36];
  EFI_HANDLE ConsoleInHandle;
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL* ConIn;
  EFI_HANDLE ConsoleOutHandle;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* ConOut;
} EFI_SYSTEM_TABLE;

extern EFI_SYSTEM_TABLE* SystemTable;

CHAR16 getwchar();
void putws(CHAR16* str);
void wprintf(const CHAR16* format, ...);