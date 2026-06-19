#ifndef GHIDRA_IMPORT_H
#define GHIDRA_IMPORT_H

#include "types.h"

#ifndef __cplusplus
typedef int bool;
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif
#ifndef _WCHAR_T
typedef u16 wchar_t;
#define _WCHAR_T
#endif
#endif

#ifndef NAN
#define NAN 0.0f
#endif

#endif
