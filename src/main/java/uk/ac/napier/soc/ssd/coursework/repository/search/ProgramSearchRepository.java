package uk.ac.napier.soc.ssd.coursework.repository.search;

import uk.ac.napier.soc.ssd.coursework.domain.Program;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

/**
 * Spring Data Elasticsearch repository for the Program entity.
 */
public interface ProgramSearchRepository extends ElasticsearchRepository<Program, Long> {
}
