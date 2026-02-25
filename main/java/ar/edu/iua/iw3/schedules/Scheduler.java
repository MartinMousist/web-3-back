package ar.edu.iua.iw3.schedules;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import ar.edu.iua.iw3.util.EmailBusiness;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableScheduling
@EnableAsync
@Slf4j
public class Scheduler {

	// fixedDelay e initialDelay se miden por defecto en milisegundos, lo varía
	// timeUnit
	@Scheduled(fixedDelay = 5, initialDelay = 8, timeUnit = TimeUnit.SECONDS)
	public void schedule1() {
		log.trace("Evento calendarizado cada 5 segundos, 8 iniciales");
	}
	
	/**
	 * A cron-like expression, extending the usual UN*X definition to include 
	 * triggers on the second, minute, hour, day of month, month, and day of week.
	 * For example, "0 * * * * MON-FRI" means once per minute on weekdays 
	 * (at the top of the minute - the 0th second).
	 * The fields read from left to right are interpreted as follows.
	 * second / minute / hour / day of month / month / day of week
	 */
	@Scheduled(cron="0 2 10 * * *")
	public void schedule2() {
		log.info("Evento calendarizado a las 10:02 AM de cada día");
	}

	@Autowired
	private EmailBusiness emailBusiness;


	@Value("${expired.product.send.to:magm@iua.edu.ar}")
	private String expiredProductSendTo;
}
