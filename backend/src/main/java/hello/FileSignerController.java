package hello;

import hello.storage.SigningService;
import hello.storage.StorageFileNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.security.UnrecoverableKeyException;

@Controller
public class FileSignerController {

    private final SigningService signingService;

    @Autowired
    public FileSignerController(SigningService signingService) {
        this.signingService = signingService;
    }

    @CrossOrigin()//origins = "http://localhost:9000")
    @PostMapping("/")
    @ResponseBody
    public ResponseEntity<Resource> sign(@RequestParam("file") MultipartFile file,
                       RedirectAttributes redirectAttributes) {

        Resource file2 = null;
        try {
            file2 = signingService.sign(file);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        try {
            long length  = file2.contentLength();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + file2.getFilename() + "\"").contentType(MediaType.APPLICATION_PDF).body(file2);

    }

    @ExceptionHandler(StorageFileNotFoundException.class)
    public ResponseEntity<?> handleStorageFileNotFound(StorageFileNotFoundException exc) {
        return ResponseEntity.notFound().build();
    }

}
