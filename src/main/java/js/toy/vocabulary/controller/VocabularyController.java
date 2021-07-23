package js.toy.vocabulary.controller;

import js.toy.vocabulary.service.VocabularyService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The type Vocabulary controller.
 */
// 초기화 되지않은 final 필드나, @NonNull 이 붙은 필드에 대해 생성자를 생성
@RequiredArgsConstructor
@RequestMapping("/api/v1/vocabulary")
@RestController
public class VocabularyController {

    // 어떠한 빈(Bean)에 생성자가 오직 하나만 있고, 생성자의 파라미터 타입이 빈으로 등록 가능한 존재라면 이 빈은 @Autowired 어노테이션 없이도 의존성 주입이 가능
    private final VocabularyService vocabularyService;

    @GetMapping("/permit-all")
    public Object permitAll() {
        return vocabularyService.test();
    }

    @GetMapping("/auth")
    public Object auth() {
        return vocabularyService.test();
    }

}
