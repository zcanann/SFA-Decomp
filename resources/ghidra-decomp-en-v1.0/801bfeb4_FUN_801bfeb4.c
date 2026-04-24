// Function: FUN_801bfeb4
// Entry: 801bfeb4
// Size: 312 bytes

void FUN_801bfeb4(int param_1)

{
  undefined4 uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_8001f4c8(param_1,1);
  *(undefined4 *)(puVar2 + 2) = uVar1;
  if (*(int *)(puVar2 + 2) != 0) {
    FUN_8001db2c(*(int *)(puVar2 + 2),2);
    FUN_8001daf0(*(undefined4 *)(puVar2 + 2),0,0xff,0,0);
    FUN_8001da18(*(undefined4 *)(puVar2 + 2),0,0xff,0,0);
    FUN_8001dc38((double)FLOAT_803e4d70,(double)FLOAT_803e4d74,*(undefined4 *)(puVar2 + 2));
    FUN_8001db54(*(undefined4 *)(puVar2 + 2),1);
    FUN_8001db6c((double)FLOAT_803e4d78,*(undefined4 *)(puVar2 + 2),1);
    FUN_8001dd40(*(undefined4 *)(puVar2 + 2),1);
    FUN_8001d730((double)FLOAT_803e4d7c,*(undefined4 *)(puVar2 + 2),0,0,0xff,0,0x7f);
    FUN_8001d714((double)FLOAT_803e4d80,*(undefined4 *)(puVar2 + 2));
  }
  *(undefined4 *)(param_1 + 0xf4) = 0xb4;
  FUN_80035df4(param_1,0,0,0);
  FUN_80035974(param_1,0);
  *puVar2 = 0;
  puVar2[1] = 0;
  FUN_80035f20(param_1);
  uVar1 = FUN_8002b588(param_1);
  FUN_8002852c(uVar1,FUN_800284cc);
  return;
}

