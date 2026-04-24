// Function: FUN_8027300c
// Entry: 8027300c
// Size: 132 bytes

undefined4 FUN_8027300c(undefined2 param_1,byte param_2,uint param_3,byte param_4)

{
  undefined4 uVar1;
  
  FUN_80285258();
  uVar1 = FUN_80271f14(param_1,param_2,param_3,param_4,
                       (uint)(byte)(&DAT_803be685)[(uint)param_4 * 2]);
  FUN_80285220();
  return uVar1;
}

