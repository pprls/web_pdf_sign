package hello.storage;

import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Path;
import java.security.UnrecoverableKeyException;
import java.util.stream.Stream;

public interface SigningService {

    void init();

    Resource sign(MultipartFile file) throws UnrecoverableKeyException;

    Stream<Path> loadAll();

    Path load(String filename);

    Resource loadAsResource(String filename);

    void deleteAll();

}
