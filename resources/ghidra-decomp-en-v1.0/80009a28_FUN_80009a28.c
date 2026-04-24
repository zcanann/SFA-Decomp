// Function: FUN_80009a28
// Entry: 80009a28
// Size: 108 bytes

void FUN_80009a28(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,int param_5)

{
  if ((param_3 != 0) || (param_4 != 0)) {
    FUN_802729d0(param_1,param_2,param_3 & 0xff,param_4 & 0xff);
  }
  if (param_5 != 0) {
    FUN_8000cfa8(param_1);
    FUN_8000d58c(param_1);
  }
  return;
}

