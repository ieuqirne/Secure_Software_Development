package uk.ac.napier.soc.ssd.coursework.repository.search;

import uk.ac.napier.soc.ssd.coursework.domain.User;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

/**
 * Spring Data Elasticsearch repository for the User entity.
 */
public interface UserSearchRepository extends ElasticsearchRepository<User, Long> {
}
