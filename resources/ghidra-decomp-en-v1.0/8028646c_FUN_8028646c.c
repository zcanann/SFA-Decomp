// Function: FUN_8028646c
// Entry: 8028646c
// Size: 36 bytes

undefined8 FUN_8028646c(uint param_1,uint param_2,int param_3)

{
  return CONCAT44(param_1 >> param_3,
                  param_2 >> param_3 | param_1 << 0x20 - param_3 | param_1 >> param_3 + -0x20);
}

