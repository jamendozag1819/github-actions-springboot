package com.app.hotel.common.controllers;

import com.app.hotel.common.requests.CustomRequest;
import com.app.hotel.common.utils.RequestUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public abstract class BaseController extends RequestUtil {
    @Autowired
    private HttpServletRequest httpRequest;

    protected HttpServletRequest getHttpRequest() {
        return  httpRequest;
    }
}
