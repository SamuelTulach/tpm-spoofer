#pragma once

#include <ntifs.h>
#include <minwindef.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <bcrypt.h>

#include "tpm20.h"
#include "tpm_defines.h"
#include "utils.h"
#include "hook.h"

#define Log(x, ...) DbgPrintEx(0, 0, "[tpm-hook] " x "\n", __VA_ARGS__)