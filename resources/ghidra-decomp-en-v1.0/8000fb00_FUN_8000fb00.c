// Function: FUN_8000fb00
// Entry: 8000fb00
// Size: 232 bytes

void FUN_8000fb00(void)

{
  double dVar1;
  
  if (DAT_803dc890 == 1) {
    FUN_80247698((double)FLOAT_803dc8a0,(double)FLOAT_803dc89c,(double)FLOAT_803dc898,
                 (double)FLOAT_803dc894,(double)FLOAT_803db260,(double)FLOAT_803db264,&DAT_80338750)
    ;
  }
  else {
    FUN_802475c8((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803db260,
                 (double)FLOAT_803db264,&DAT_80338750);
    FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,(double)FLOAT_803de628,
                 (double)FLOAT_803de628,(double)FLOAT_803de62c,(double)FLOAT_803de62c,&DAT_80396850)
    ;
    dVar1 = (double)FLOAT_803de62c;
    FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar1,dVar1,dVar1,dVar1,&DAT_803967f0
                );
    dVar1 = (double)FLOAT_803de62c;
    FUN_80247340((double)FLOAT_803dc8a4,(double)FLOAT_803db268,dVar1,(double)FLOAT_803de630,dVar1,
                 dVar1,&DAT_80396820);
  }
  FUN_8025cf48(&DAT_80338750,DAT_803dc890);
  return;
}

