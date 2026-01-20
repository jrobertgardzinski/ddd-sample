package io.cucumber.skeleton;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import org.opentest4j.TestAbortedException;

public class StepDefinitions {
    @Given("I have {int} cukes in my belly")
    public void I_have_cukes_in_my_belly(int cukes) {
        Belly belly = new Belly();
        throw new RuntimeException("blah");
        //belly.eat(cukes);
    }

    @When("I wait {int} hour")
    public void i_wait_hour(Integer int1) {
        // Write code here that turns the phrase above into concrete actions
        throw new TestAbortedException("TODO");
    }

}
