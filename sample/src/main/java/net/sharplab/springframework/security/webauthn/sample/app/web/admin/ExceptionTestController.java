package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.terasoluna.gfw.common.exception.BusinessException;
import org.terasoluna.gfw.common.exception.SystemException;
import org.terasoluna.gfw.common.message.ResultMessages;

/**
 * Controller for error handling test
 */
@Controller
public class ExceptionTestController {

    /**
     * Throws business exception to simulate an unhandled business exception.
     */
    @RequestMapping("/admin/error/throwBusinessException")
    public void throwBusinessError() {
        throw new BusinessException(ResultMessages.error().add(MessageCodes.Error.UNKNOWN));
    }

    /**
     * Throws business exception to simulate an unhandled business exception.
     */
    @RequestMapping("/admin/error/throwSystemException")
    public void throwSystemError() {
        throw new SystemException(MessageCodes.Error.UNKNOWN, "exception message");
    }

}
