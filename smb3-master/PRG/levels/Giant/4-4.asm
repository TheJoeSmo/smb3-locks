; Original address was $B2AD
; 4-4
    .word W404_BonusL   ; Alternate level layout
    .word Empty_ObjLayout   ; Alternate object layout
    .byte LEVEL1_SIZE_08 | LEVEL1_YSTART_000
    .byte LEVEL2_BGPAL_01 | LEVEL2_OBJPAL_08 | LEVEL2_XSTART_18
    .byte LEVEL3_TILESET_01 | LEVEL3_VSCROLL_FREE | LEVEL3_PIPENOTEXIT
    .byte 11 & %00011111 | LEVEL4_INITACT_NOTHING
    .byte LEVEL5_BGM_UNDERWATER | LEVEL5_TIME_300

    .byte $4E, $00, $8C, $7F, $45, $00, $8B, $16, $07, $00, $52, $09, $00, $52, $0B, $00
    .byte $52, $0D, $00, $52, $0F, $00, $52, $11, $00, $52, $13, $00, $52, $0B, $08, $50
    .byte $17, $0C, $51, $09, $08, $90, $13, $0E, $91, $19, $00, $74, $19, $0C, $71, $19
    .byte $12, $70, $19, $16, $78, $35, $02, $C1, $37, $06, $A1, $E0, $71, $10, $01, $16
    .byte $53, $03, $16, $53, $05, $16, $53, $07, $16, $53, $09, $16, $53, $0B, $16, $53
    .byte $0D, $16, $53, $0F, $16, $53, $11, $16, $53, $13, $16, $53, $0B, $12, $50, $0D
    .byte $12, $50, $0F, $12, $50, $11, $12, $50, $13, $12, $50, $15, $12, $50, $17, $12
    .byte $50, $2B, $11, $00, $19, $2C, $77, $13, $26, $50, $13, $2C, $50, $15, $20, $91
    .byte $37, $24, $A1, $19, $3E, $74, $11, $3A, $50, $13, $3A, $50, $15, $3A, $50, $15
    .byte $32, $52, $13, $34, $90, $11, $4C, $50, $13, $46, $50, $15, $40, $50, $15, $4C
    .byte $50, $19, $4E, $72, $37, $44, $A1, $0D, $52, $50, $11, $5C, $50, $15, $5C, $50
    .byte $17, $5C, $50, $17, $50, $90, $19, $5A, $72, $11, $64, $50, $13, $60, $50, $13
    .byte $68, $50, $13, $64, $50, $15, $64, $50, $0F, $64, $50, $17, $68, $50, $19, $66
    .byte $72, $01, $7E, $50, $03, $7E, $50, $05, $7E, $50, $07, $7E, $50, $09, $7E, $50
    .byte $0B, $7E, $50, $0D, $7E, $50, $0F, $7E, $50, $11, $7A, $52, $13, $78, $53, $15
    .byte $76, $54, $17, $74, $55, $19, $72, $76, $6F, $7C, $61, $FF