// Function: FUN_800217f4
// Entry: 800217f4
// Size: 100 bytes

int FUN_800217f4(uint param_1,uint param_2)

{
  double dVar1;
  
  dVar1 = (double)FUN_802924b4((double)(float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) -
                                              DOUBLE_803de7e0),
                               (double)(float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) -
                                              DOUBLE_803de7e0));
  return (int)(DOUBLE_803de7d8 * dVar1);
}

