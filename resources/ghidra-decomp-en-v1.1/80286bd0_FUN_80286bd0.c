// Function: FUN_80286bd0
// Entry: 80286bd0
// Size: 36 bytes

undefined8 FUN_80286bd0(uint param_1,uint param_2,int param_3)

{
  return CONCAT44(param_1 >> param_3,
                  param_2 >> param_3 | param_1 << 0x20 - param_3 | param_1 >> param_3 + -0x20);
}

