package com.jrobertgardzinski.repository;

import com.jrobertgardzinski.entity.Comment;
import com.jrobertgardzinski.vo.Author;
import com.jrobertgardzinski.vo.Id;
import jakarta.data.page.Page;

public interface Repository {
    Page<Comment> getPageBy(long pageNumber);
    Comment create(Comment comment);
    Comment edit(Comment comment);
    boolean deleteBy(Id id);
    boolean deleteBy(Author author);
}
