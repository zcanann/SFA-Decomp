// Function: FUN_8002330c
// Entry: 8002330c
// Size: 220 bytes

void FUN_8002330c(undefined4 param_1)

{
  if (DAT_803dcb40 == 2000) {
    FUN_8004a868();
    FUN_8004a43c(1,0);
    FUN_8004a868();
    FUN_8004a43c(1,0);
    for (; 0 < DAT_803dcb40; DAT_803dcb40 = DAT_803dcb40 + -1) {
      FUN_800233e8(DAT_8033c820);
      DAT_8033c820 = *(undefined4 *)(&DAT_8033c818 + DAT_803dcb40 * 8);
      DAT_8033c824 = (&DAT_8033c81c)[DAT_803dcb40 * 8];
    }
    FUN_8007d6dc(s__7______mm_Error__________stbf_s_802ca9fc);
  }
  (&DAT_8033c820)[DAT_803dcb40 * 2] = param_1;
  (&DAT_8033c824)[DAT_803dcb40 * 8] = (char)DAT_803dcb3c;
  DAT_803dcb40 = DAT_803dcb40 + 1;
  return;
}

