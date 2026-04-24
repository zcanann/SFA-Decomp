// Function: FUN_80062808
// Entry: 80062808
// Size: 140 bytes

void FUN_80062808(void)

{
  if (DAT_803db658 == '\0') {
    return;
  }
  DAT_803dceec = '\x01' - DAT_803dceec;
  DAT_803dceed = '\x01' - DAT_803dceed;
  DAT_803dceee = '\x01' - DAT_803dceee;
  DAT_803dcef4 = 0;
  DAT_803dcef8 = 0;
  DAT_803dcefc = 0;
  DAT_803dcf04 = *(undefined4 *)(&DAT_803dcf24 + DAT_803dceec * 4);
  DAT_803dcf08 = *(undefined4 *)(&DAT_803dcf24 + DAT_803dceec * 4);
  DAT_803dcf0c = DAT_803dcf20;
  DAT_803dcf10 = DAT_803dcf20;
  DAT_803dcf14 = DAT_803dcf1c;
  DAT_803dcf18 = DAT_803dcf1c;
  return;
}

