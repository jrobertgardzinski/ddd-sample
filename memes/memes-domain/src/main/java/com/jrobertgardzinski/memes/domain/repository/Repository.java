package com.jrobertgardzinski.memes.domain.repository;

import com.jrobertgardzinski.memes.domain.entity.Meme;
import com.jrobertgardzinski.memes.domain.vo.Creator;
import com.jrobertgardzinski.memes.domain.vo.Id;
import jakarta.data.page.Page;

public interface Repository {
    Page<Meme> getPageBy(long pageNumber);
    Meme create(Meme meme);
    boolean deleteBy(Id id);
    boolean deleteByEmail(Creator creator);
}
