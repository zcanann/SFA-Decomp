// Function: FUN_80286bac
// Entry: 80286bac
// Size: 36 bytes

undefined8 FUN_80286bac(int param_1,uint param_2,int param_3)

{
  return CONCAT44(param_1 << param_3 | param_2 >> 0x20 - param_3 | param_2 << param_3 + -0x20,
                  param_2 << param_3);
}

