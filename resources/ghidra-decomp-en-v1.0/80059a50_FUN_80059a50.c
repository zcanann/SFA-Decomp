// Function: FUN_80059a50
// Entry: 80059a50
// Size: 112 bytes

void FUN_80059a50(int param_1)

{
  if ((&DAT_80386468)[param_1] != 0) {
    FUN_8005972c((&DAT_80386468)[param_1],param_1 * 0x8c + -0x7fc7dd38,param_1,1);
    FUN_80023800((&DAT_80386468)[param_1]);
    (&DAT_80386468)[param_1] = 0;
  }
  return;
}

