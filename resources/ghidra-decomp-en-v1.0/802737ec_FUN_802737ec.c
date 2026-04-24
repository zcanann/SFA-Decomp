// Function: FUN_802737ec
// Entry: 802737ec
// Size: 132 bytes

void FUN_802737ec(int param_1)

{
  byte bVar1;
  
  bVar1 = (&DAT_803be380)[param_1 * 100];
  if ((bVar1 < 3) && (bVar1 != 0)) {
    if (bVar1 == 2) {
      FUN_80279fac((&DAT_803be3c0)[param_1 * 0x19]);
    }
    (&DAT_803be380)[param_1 * 100] = 3;
    (*(code *)(&DAT_803be384)[param_1 * 0x19])(0,0,0,0,(&DAT_803be3c4)[param_1 * 0x19]);
  }
  return;
}

