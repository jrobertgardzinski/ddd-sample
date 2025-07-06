package com.jrobertgardzinski.entity;

import com.jrobertgardzinski.vo.Content;
import com.jrobertgardzinski.vo.Id;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Comment {
    @Getter
    private final String extAuthor;
    @Getter
    private final String extMeme;
    @Getter
    private final Id id;
    @Getter
    private final Content content;
}
