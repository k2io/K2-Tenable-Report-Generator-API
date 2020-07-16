package com.k2cybersecurity.tenable.reportgenerator;

import com.itextpdf.io.font.otf.Glyph;
import com.itextpdf.io.font.otf.GlyphLine;
import com.itextpdf.layout.splitting.DefaultSplitCharacters;

//public class CustomSplitCharacters {
//
//}
public class CustomSplitCharacters extends DefaultSplitCharacters {
	@Override
	public boolean isSplitCharacter(GlyphLine text, int glyphPos) {
		if (!text.get(glyphPos).hasValidUnicode()) {
			return false;
		}
		boolean baseResult = super.isSplitCharacter(text, glyphPos);
		boolean myResult = false;
		Glyph glyph = text.get(glyphPos);
		if (glyph.getUnicode() == '?' || glyph.getUnicode() == '%' || glyph.getUnicode() == '/'
				|| glyph.getUnicode() == '=') {
			myResult = true;
		}
		return myResult || baseResult;
	}
}