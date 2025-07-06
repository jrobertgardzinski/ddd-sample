package com.jrobertgardzinski.memes.domain.entity;

import com.jrobertgardzinski.memes.domain.vo.Creator;
import com.jrobertgardzinski.memes.domain.vo.ImageData;
import com.jrobertgardzinski.memes.domain.vo.Id;
import com.jrobertgardzinski.memes.domain.vo.SizeInBytes;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Meme {
    @Getter
    private final Creator creator;
    @Getter
    private final Id id;
    @Getter
    private final ImageData imageData;
    @Getter
    private final SizeInBytes sizeInBytes;
}
